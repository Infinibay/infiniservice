# Async Patterns in InfiniService

## Overview

InfiniService leverages Rust's async/await ecosystem with Tokio as the runtime. This document covers the async patterns, best practices, and common pitfalls.

## Tokio Runtime

### Runtime Configuration

```rust
// Main entry point with Tokio runtime
#[tokio::main]
async fn main() -> Result<()> {
    // Default runtime with all features
    run_service().await
}

// Custom runtime configuration
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    run_service().await
}

// Manual runtime creation
fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("infiniservice-worker")
        .enable_all()
        .build()
        .unwrap();
        
    runtime.block_on(async {
        run_service().await
    });
}
```

## Core Async Patterns

### Service Loop Pattern

```rust
pub async fn run(&mut self) -> Result<()> {
    // Create intervals for different tasks
    let mut metrics_interval = interval(Duration::from_secs(30));
    let mut command_interval = interval(Duration::from_millis(100));
    let mut health_check = interval(Duration::from_secs(60));
    
    // Main service loop
    loop {
        tokio::select! {
            // Periodic metrics collection
            _ = metrics_interval.tick() => {
                if let Err(e) = self.collect_and_send_metrics().await {
                    error!("Metrics collection failed: {}", e);
                    // Continue running despite errors
                }
            }
            
            // Command checking
            _ = command_interval.tick() => {
                if let Err(e) = self.check_and_execute_commands().await {
                    error!("Command execution failed: {}", e);
                }
            }
            
            // Health monitoring
            _ = health_check.tick() => {
                self.perform_health_check().await;
            }
            
            // Shutdown signal
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }
    
    // Graceful shutdown
    self.shutdown().await
}
```

### Concurrent Task Spawning

```rust
pub async fn process_multiple_tasks(&self, tasks: Vec<Task>) -> Vec<Result<TaskResult>> {
    // Spawn all tasks concurrently
    let handles: Vec<_> = tasks
        .into_iter()
        .map(|task| {
            tokio::spawn(async move {
                process_task(task).await
            })
        })
        .collect();
    
    // Wait for all tasks to complete
    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(e) => results.push(Err(anyhow!("Task panicked: {}", e))),
        }
    }
    
    results
}
```

### Timeout Pattern

```rust
pub async fn execute_with_timeout<T>(
    future: impl Future<Output = Result<T>>,
    duration: Duration,
) -> Result<T> {
    match timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("Operation timed out after {:?}", duration)),
    }
}

// Usage
async fn collect_metrics_with_timeout(&mut self) -> Result<SystemMetrics> {
    execute_with_timeout(
        self.collector.collect_async(),
        Duration::from_secs(5)
    ).await
}
```

### Retry Pattern with Backoff

```rust
pub async fn retry_with_backoff<T, F, Fut>(
    mut operation: F,
    max_retries: u32,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut delay = Duration::from_millis(100);
    let max_delay = Duration::from_secs(30);
    
    for attempt in 0..max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if attempt < max_retries - 1 => {
                warn!("Attempt {} failed: {}, retrying in {:?}", attempt + 1, e, delay);
                sleep(delay).await;
                
                // Exponential backoff with jitter
                delay = (delay * 2).min(max_delay);
                let jitter = delay / 10;
                delay += Duration::from_millis(rand::random::<u64>() % jitter.as_millis() as u64);
            }
            Err(e) => return Err(e),
        }
    }
    
    unreachable!()
}
```

## Async I/O Patterns

### Async File Operations

```rust
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn read_config_async(path: &Path) -> Result<Config> {
    let contents = fs::read_to_string(path).await?;
    toml::from_str(&contents).map_err(Into::into)
}

pub async fn write_metrics_async(path: &Path, metrics: &SystemMetrics) -> Result<()> {
    let json = serde_json::to_string_pretty(metrics)?;
    fs::write(path, json).await.map_err(Into::into)
}

// Streaming file read
pub async fn stream_large_file(path: &Path) -> Result<()> {
    let mut file = fs::File::open(path).await?;
    let mut buffer = vec![0; 8192];
    
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        
        // Process chunk
        process_chunk(&buffer[..n]).await?;
    }
    
    Ok(())
}
```

### Async VirtIO Communication

```rust
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub struct AsyncVirtioSerial {
    reader: BufReader<tokio::fs::File>,
    writer: tokio::fs::File,
}

impl AsyncVirtioSerial {
    pub async fn send_message<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let json = serde_json::to_string(msg)?;
        self.writer.write_all(json.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }
    
    pub async fn receive_message(&mut self) -> Result<String> {
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        Ok(line.trim().to_string())
    }
    
    pub async fn message_loop(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                // Read incoming messages
                line = self.reader.read_line(&mut String::new()) => {
                    match line {
                        Ok(0) => break, // EOF
                        Ok(_) => self.handle_message(line?).await?,
                        Err(e) => {
                            error!("Read error: {}", e);
                            break;
                        }
                    }
                }
                
                // Send periodic metrics
                _ = sleep(Duration::from_secs(30)) => {
                    self.send_metrics().await?;
                }
            }
        }
        
        Ok(())
    }
}
```

## Channel Communication

### Multi-Producer Single-Consumer (MPSC)

```rust
use tokio::sync::mpsc;

pub struct CommandProcessor {
    receiver: mpsc::Receiver<Command>,
}

impl CommandProcessor {
    pub async fn run(&mut self) -> Result<()> {
        while let Some(command) = self.receiver.recv().await {
            // Process commands sequentially
            self.execute_command(command).await?;
        }
        Ok(())
    }
}

// Usage
pub async fn setup_command_pipeline() -> Result<()> {
    let (tx, rx) = mpsc::channel(100);
    
    // Spawn command processor
    let processor = CommandProcessor { receiver: rx };
    tokio::spawn(async move {
        processor.run().await
    });
    
    // Multiple producers can send commands
    let tx1 = tx.clone();
    tokio::spawn(async move {
        tx1.send(Command::Collect).await.unwrap();
    });
    
    let tx2 = tx.clone();
    tokio::spawn(async move {
        tx2.send(Command::Execute("ls".into())).await.unwrap();
    });
    
    Ok(())
}
```

### Broadcast Channel

```rust
use tokio::sync::broadcast;

pub struct MetricsPublisher {
    sender: broadcast::Sender<SystemMetrics>,
}

impl MetricsPublisher {
    pub async fn publish_metrics(&self) -> Result<()> {
        loop {
            let metrics = collect_metrics().await?;
            
            // Broadcast to all subscribers
            if let Err(e) = self.sender.send(metrics) {
                debug!("No subscribers: {}", e);
            }
            
            sleep(Duration::from_secs(30)).await;
        }
    }
}

// Multiple subscribers
pub async fn setup_metrics_subscribers(sender: broadcast::Sender<SystemMetrics>) {
    // Subscriber 1: Log metrics
    let mut rx1 = sender.subscribe();
    tokio::spawn(async move {
        while let Ok(metrics) = rx1.recv().await {
            info!("Metrics: {:?}", metrics);
        }
    });
    
    // Subscriber 2: Send to backend
    let mut rx2 = sender.subscribe();
    tokio::spawn(async move {
        while let Ok(metrics) = rx2.recv().await {
            send_to_backend(metrics).await;
        }
    });
}
```

## Synchronization Primitives

### Async Mutex

```rust
use tokio::sync::Mutex;
use std::sync::Arc;

pub struct SharedState {
    metrics: Arc<Mutex<SystemMetrics>>,
}

impl SharedState {
    pub async fn update_metrics(&self, new_metrics: SystemMetrics) {
        let mut metrics = self.metrics.lock().await;
        *metrics = new_metrics;
    }
    
    pub async fn get_metrics(&self) -> SystemMetrics {
        let metrics = self.metrics.lock().await;
        metrics.clone()
    }
}
```

### RwLock for Read-Heavy Workloads

```rust
use tokio::sync::RwLock;

pub struct MetricsCache {
    data: Arc<RwLock<HashMap<String, SystemMetrics>>>,
}

impl MetricsCache {
    pub async fn get(&self, key: &str) -> Option<SystemMetrics> {
        let cache = self.data.read().await;
        cache.get(key).cloned()
    }
    
    pub async fn insert(&self, key: String, metrics: SystemMetrics) {
        let mut cache = self.data.write().await;
        cache.insert(key, metrics);
    }
    
    pub async fn get_all(&self) -> Vec<SystemMetrics> {
        let cache = self.data.read().await;
        cache.values().cloned().collect()
    }
}
```

### Semaphore for Rate Limiting

```rust
use tokio::sync::Semaphore;

pub struct RateLimitedExecutor {
    semaphore: Arc<Semaphore>,
}

impl RateLimitedExecutor {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }
    
    pub async fn execute<F, T>(&self, task: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        // Acquire permit
        let _permit = self.semaphore.acquire().await?;
        
        // Execute task while holding permit
        task.await
    }
}

// Usage: Limit concurrent command execution
pub async fn execute_commands(commands: Vec<Command>) -> Vec<Result<()>> {
    let executor = RateLimitedExecutor::new(5); // Max 5 concurrent
    
    let futures = commands.into_iter().map(|cmd| {
        let executor = executor.clone();
        async move {
            executor.execute(async move {
                execute_single_command(cmd).await
            }).await
        }
    });
    
    futures::future::join_all(futures).await
}
```

## Stream Processing

### Async Stream Pattern

```rust
use tokio_stream::{Stream, StreamExt};

pub fn metrics_stream() -> impl Stream<Item = SystemMetrics> {
    async_stream::stream! {
        let mut interval = interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            match collect_metrics().await {
                Ok(metrics) => yield metrics,
                Err(e) => {
                    error!("Failed to collect metrics: {}", e);
                    continue;
                }
            }
        }
    }
}

// Consume stream
pub async fn process_metrics_stream() -> Result<()> {
    let mut stream = metrics_stream();
    
    while let Some(metrics) = stream.next().await {
        process_metrics(metrics).await?;
    }
    
    Ok(())
}
```

## Error Handling in Async Context

### Async Error Propagation

```rust
pub async fn complex_operation() -> Result<()> {
    // Early return on error
    let config = load_config().await?;
    
    // Handle specific errors
    let metrics = match collect_metrics().await {
        Ok(m) => m,
        Err(e) if e.to_string().contains("permission") => {
            warn!("Permission denied, using default metrics");
            SystemMetrics::default()
        }
        Err(e) => return Err(e),
    };
    
    // Parallel error handling
    let (r1, r2) = tokio::join!(
        send_metrics(metrics.clone()),
        store_metrics(metrics)
    );
    
    r1?;
    r2?;
    
    Ok(())
}
```

## Performance Optimization

### Avoiding Blocking Operations

```rust
// Bad: Blocks the async runtime
pub async fn bad_example() {
    std::thread::sleep(Duration::from_secs(1)); // BLOCKS!
    let data = std::fs::read_to_string("file.txt").unwrap(); // BLOCKS!
}

// Good: Use async alternatives
pub async fn good_example() {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let data = tokio::fs::read_to_string("file.txt").await.unwrap();
}

// For CPU-intensive work, use spawn_blocking
pub async fn cpu_intensive_task(data: Vec<u8>) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        // CPU-intensive computation
        expensive_computation(data)
    })
    .await?
}
```

### Buffer Management

```rust
use tokio::io::BufWriter;

pub async fn write_large_data(data: &[u8]) -> Result<()> {
    let file = tokio::fs::File::create("output.bin").await?;
    let mut writer = BufWriter::new(file);
    
    // Write in chunks
    for chunk in data.chunks(8192) {
        writer.write_all(chunk).await?;
    }
    
    writer.flush().await?;
    Ok(())
}
```

## Testing Async Code

### Async Test Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;
    
    #[test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
    
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_operations() {
        let (r1, r2) = tokio::join!(
            operation_one(),
            operation_two()
        );
        
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }
    
    #[test]
    async fn test_with_timeout() {
        let result = timeout(
            Duration::from_millis(100),
            slow_operation()
        ).await;
        
        assert!(result.is_err()); // Should timeout
    }
}
```

## Common Pitfalls

1. **Blocking the Runtime**: Never use blocking I/O in async functions
2. **Forgetting .await**: Futures do nothing until awaited
3. **Holding Locks Across Await Points**: Can cause deadlocks
4. **Unbounded Channels**: Can cause memory issues
5. **Not Handling Errors**: Always handle or propagate errors

## Best Practices

1. **Use tokio::select!** for concurrent operations
2. **Implement timeouts** for all external operations
3. **Use channels** for inter-task communication
4. **Spawn tasks** for independent work
5. **Use Arc<T>** for shared ownership across tasks
6. **Profile async code** to identify bottlenecks
7. **Test with multiple runtime configurations**