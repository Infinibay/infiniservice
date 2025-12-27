//! Generic async cache management for update checkers
//!
//! This module provides a reusable cache abstraction that handles the common pattern
//! of executing blocking system commands in async context and caching the results.
//!
//! # Example: Simple cache without TTL
//! ```no_run
//! use crate::commands::common::cache::AsyncCache;
//! use std::collections::HashMap;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut cache = AsyncCache::<String, String>::new("apt-packages");
//!
//!     cache.build_cache(|| {
//!         let mut map = HashMap::new();
//!         // Execute command and parse output
//!         map.insert("firefox".to_string(), "91.0".to_string());
//!         Ok(map)
//!     }).await?;
//!
//!     if let Some(version) = cache.get(&"firefox".to_string()) {
//!         println!("Firefox version: {}", version);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Example: Cache with TTL (5 minutes)
//! ```no_run
//! use crate::commands::common::cache::AsyncCache;
//! use std::time::Duration;
//! use std::collections::HashMap;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut cache = AsyncCache::<String, String>::with_ttl("winget-updates", Duration::from_secs(300));
//!
//!     // First call builds the cache
//!     cache.build_or_refresh(|| {
//!         let mut map = HashMap::new();
//!         map.insert("package".to_string(), "1.0".to_string());
//!         Ok(map)
//!     }).await?;
//!
//!     // Second call within 5 minutes uses cached data
//!     cache.build_or_refresh(|| {
//!         let mut map = HashMap::new();
//!         map.insert("package".to_string(), "1.0".to_string());
//!         Ok(map)
//!     }).await?; // No rebuild, uses cache
//!     Ok(())
//! }
//! ```
//!
//! # Migration Pattern
//!
//! **Before** (duplicated in each checker):
//! ```rust,ignore
//! let cache = tokio::task::spawn_blocking(move || -> UpdateCheckResult<HashMap<String, String>> {
//!     let mut packages = HashMap::new();
//!     let output = Command::new("apt").args(["list", "--upgradable"]).output()?;
//!     // Parse output...
//!     Ok(packages)
//! }).await
//! .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to spawn: {}", e)))?
//! .map_err(|e| e)?;
//! ```
//!
//! **After** (using AsyncCache):
//! ```rust,ignore
//! let mut cache = AsyncCache::new("apt-packages");
//! cache.build_cache(|| {
//!     let mut packages = HashMap::new();
//!     let output = Command::new("apt").args(["list", "--upgradable"]).output()?;
//!     // Parse output...
//!     Ok(packages)
//! }).await?;
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, SystemTime};

use log::debug;

use super::super::update_checker::{UpdateCheckError, UpdateCheckResult};

/// A generic async cache for storing key-value data with optional TTL support.
///
/// This cache is designed to work with the `spawn_blocking` pattern commonly used
/// when executing blocking system commands in an async context. Each update checker
/// can have its own cache instance.
///
/// # Type Parameters
/// - `K`: The key type, must implement `Eq + Hash + Clone + Send + 'static`
/// - `V`: The value type, must implement `Clone + Send + 'static`
///
/// # Thread Safety
/// This structure does not require `Arc<Mutex<>>` because each checker has its own instance.
/// The generic types require `Send + 'static` to work with `spawn_blocking`.
pub struct AsyncCache<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// The cached data
    data: Option<HashMap<K, V>>,
    /// When the cache was last built
    timestamp: Option<SystemTime>,
    /// Optional time-to-live for automatic expiration
    ttl: Option<Duration>,
    /// Descriptive name for logging
    name: String,
}

impl<K, V> AsyncCache<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// Creates a new cache without TTL (cache never expires automatically).
    ///
    /// # Arguments
    /// * `name` - A descriptive name for logging purposes
    ///
    /// # Example
    /// ```no_run
    /// use crate::commands::common::cache::AsyncCache;
    /// let cache = AsyncCache::<String, String>::new("apt-packages");
    /// ```
    pub fn new(name: &str) -> Self {
        Self {
            data: None,
            timestamp: None,
            ttl: None,
            name: name.to_string(),
        }
    }

    /// Creates a new cache with TTL (cache expires after the specified duration).
    ///
    /// # Arguments
    /// * `name` - A descriptive name for logging purposes
    /// * `ttl` - Time-to-live duration after which the cache is considered invalid
    ///
    /// # Example
    /// ```no_run
    /// use crate::commands::common::cache::AsyncCache;
    /// use std::time::Duration;
    /// let cache = AsyncCache::<String, String>::with_ttl("winget-updates", Duration::from_secs(300));
    /// ```
    pub fn with_ttl(name: &str, ttl: Duration) -> Self {
        Self {
            data: None,
            timestamp: None,
            ttl: Some(ttl),
            name: name.to_string(),
        }
    }

    /// Builds the cache by executing the provided builder function in a blocking task.
    ///
    /// This method uses `tokio::task::spawn_blocking` to execute the builder function
    /// in a thread pool designed for blocking operations, avoiding blocking the async runtime.
    ///
    /// # Arguments
    /// * `builder_fn` - A function that returns a `HashMap<K, V>` or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// - The spawn_blocking task fails to join
    /// - The builder function returns an error
    ///
    /// # Example
    /// ```no_run
    /// use crate::commands::common::cache::AsyncCache;
    /// use std::collections::HashMap;
    ///
    /// async fn example() {
    ///     let mut cache = AsyncCache::<String, String>::new("test");
    ///     cache.build_cache(|| {
    ///         let mut map = HashMap::new();
    ///         map.insert("key".to_string(), "value".to_string());
    ///         Ok(map)
    ///     }).await.unwrap();
    /// }
    /// ```
    pub async fn build_cache<F>(&mut self, builder_fn: F) -> UpdateCheckResult<()>
    where
        F: FnOnce() -> UpdateCheckResult<HashMap<K, V>> + Send + 'static,
    {
        debug!("Building cache for {}", self.name);

        let result = tokio::task::spawn_blocking(builder_fn)
            .await
            .map_err(|e| {
                UpdateCheckError::PlatformError(format!(
                    "Failed to spawn blocking task for {}: {}",
                    self.name, e
                ))
            })?;

        let data = result?;
        let count = data.len();

        self.data = Some(data);
        self.timestamp = Some(SystemTime::now());

        debug!(
            "Cache built successfully for {} with {} entries",
            self.name, count
        );

        Ok(())
    }

    /// Builds the cache only if it's not valid (expired or not built).
    ///
    /// This method is useful for optimizing repeated calls by avoiding
    /// unnecessary cache rebuilds when the data is still fresh.
    ///
    /// # Arguments
    /// * `builder_fn` - A function that returns a `HashMap<K, V>` or an error
    ///
    /// # Returns
    /// - `Ok(())` if the cache is already valid (no rebuild)
    /// - `Ok(())` if the cache was successfully rebuilt
    /// - `Err(...)` if the rebuild failed
    pub async fn build_or_refresh<F>(&mut self, builder_fn: F) -> UpdateCheckResult<()>
    where
        F: FnOnce() -> UpdateCheckResult<HashMap<K, V>> + Send + 'static,
    {
        if self.is_valid() {
            debug!("Cache for {} is still valid, skipping rebuild", self.name);
            return Ok(());
        }

        self.build_cache(builder_fn).await
    }

    /// Gets a value from the cache by key.
    ///
    /// # Arguments
    /// * `key` - The key to look up
    ///
    /// # Returns
    /// - `Some(V)` if the key exists in the cache
    /// - `None` if the cache is not built or the key doesn't exist
    pub fn get(&self, key: &K) -> Option<V> {
        self.data.as_ref()?.get(key).cloned()
    }

    /// Gets a reference to the entire cached HashMap.
    ///
    /// # Returns
    /// - `Some(&HashMap<K, V>)` if the cache is built
    /// - `None` if the cache is not built
    pub fn get_all(&self) -> Option<&HashMap<K, V>> {
        self.data.as_ref()
    }

    /// Checks if a key exists in the cache.
    ///
    /// # Arguments
    /// * `key` - The key to check
    ///
    /// # Returns
    /// - `true` if the key exists in the cache
    /// - `false` if the cache is not built or the key doesn't exist
    pub fn contains_key(&self, key: &K) -> bool {
        self.data
            .as_ref()
            .map(|d| d.contains_key(key))
            .unwrap_or(false)
    }

    /// Returns the number of entries in the cache.
    ///
    /// # Returns
    /// - The number of entries if the cache is built
    /// - `0` if the cache is not built
    pub fn len(&self) -> usize {
        self.data.as_ref().map(|d| d.len()).unwrap_or(0)
    }

    /// Checks if the cache is empty or not built.
    ///
    /// # Returns
    /// - `true` if the cache is not built or has no entries
    /// - `false` if the cache has at least one entry
    pub fn is_empty(&self) -> bool {
        self.data.as_ref().map(|d| d.is_empty()).unwrap_or(true)
    }

    /// Checks if the cache is valid (built and not expired).
    ///
    /// # Returns
    /// - `false` if the cache is not built
    /// - `true` if the cache is built and has no TTL
    /// - `true` if the cache is built and hasn't expired
    /// - `false` if the cache has expired (age >= ttl)
    pub fn is_valid(&self) -> bool {
        if self.data.is_none() {
            return false;
        }

        // If no TTL, cache is always valid once built
        let Some(ttl) = self.ttl else {
            return true;
        };

        // Check if timestamp exists and cache hasn't expired
        let Some(timestamp) = self.timestamp else {
            return false;
        };

        let age = timestamp.elapsed().unwrap_or(Duration::MAX);
        age < ttl
    }

    /// Invalidates the cache, clearing all data.
    ///
    /// After calling this method, the cache will need to be rebuilt.
    pub fn invalidate(&mut self) {
        self.data = None;
        self.timestamp = None;
        debug!("Cache invalidated for {}", self.name);
    }

    /// Returns the age of the cache since it was last built.
    ///
    /// # Returns
    /// - `Some(Duration)` if the cache has been built
    /// - `None` if the cache has never been built
    pub fn age(&self) -> Option<Duration> {
        self.timestamp?.elapsed().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_cache_creation() {
        let cache = AsyncCache::<String, String>::new("test");
        assert!(cache.is_empty());
        assert!(!cache.is_valid());
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn test_cache_build() {
        let mut cache = AsyncCache::<String, String>::new("test");

        let result = cache
            .build_cache(|| {
                let mut map = HashMap::new();
                map.insert("key1".to_string(), "value1".to_string());
                map.insert("key2".to_string(), "value2".to_string());
                Ok(map)
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
        assert!(cache.is_valid());
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));
        assert_eq!(cache.get(&"key3".to_string()), None);
    }

    #[tokio::test]
    async fn test_cache_with_ttl() {
        let mut cache =
            AsyncCache::<String, String>::with_ttl("test", Duration::from_millis(100));

        cache
            .build_cache(|| {
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        // Cache should be valid immediately after building
        assert!(cache.is_valid());

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Cache should be invalid after TTL
        assert!(!cache.is_valid());
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let mut cache = AsyncCache::<String, String>::new("test");

        cache
            .build_cache(|| {
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        assert!(cache.is_valid());
        assert!(!cache.is_empty());

        cache.invalidate();

        assert!(!cache.is_valid());
        assert!(cache.is_empty());
        assert_eq!(cache.get(&"key".to_string()), None);
    }

    #[tokio::test]
    async fn test_build_or_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let mut cache = AsyncCache::<String, String>::new("test");

        // First call should build
        let count_clone = call_count.clone();
        cache
            .build_or_refresh(move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call should not rebuild (cache is valid)
        let count_clone = call_count.clone();
        cache
            .build_or_refresh(move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        // Counter should still be 1 (second builder was not called)
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_build_or_refresh_with_expired_ttl() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let mut cache =
            AsyncCache::<String, String>::with_ttl("test", Duration::from_millis(50));

        // First call should build
        let count_clone = call_count.clone();
        cache
            .build_or_refresh(move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Third call should rebuild (cache expired)
        let count_clone = call_count.clone();
        cache
            .build_or_refresh(move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                let mut map = HashMap::new();
                map.insert("key".to_string(), "new_value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        // Counter should be 2 (cache was rebuilt after expiration)
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            cache.get(&"key".to_string()),
            Some("new_value".to_string())
        );
    }

    #[tokio::test]
    async fn test_spawn_blocking_error_handling() {
        let mut cache = AsyncCache::<String, String>::new("test");

        let result = cache
            .build_cache(|| {
                Err(UpdateCheckError::PlatformError(
                    "Simulated error".to_string(),
                ))
            })
            .await;

        assert!(result.is_err());
        match result {
            Err(UpdateCheckError::PlatformError(msg)) => {
                assert_eq!(msg, "Simulated error");
            }
            _ => panic!("Expected PlatformError"),
        }

        // Cache should not be valid after failed build
        assert!(!cache.is_valid());
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn test_contains_key() {
        let mut cache = AsyncCache::<String, String>::new("test");

        assert!(!cache.contains_key(&"key".to_string()));

        cache
            .build_cache(|| {
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        assert!(cache.contains_key(&"key".to_string()));
        assert!(!cache.contains_key(&"nonexistent".to_string()));
    }

    #[tokio::test]
    async fn test_get_all() {
        let mut cache = AsyncCache::<String, String>::new("test");

        assert!(cache.get_all().is_none());

        cache
            .build_cache(|| {
                let mut map = HashMap::new();
                map.insert("key1".to_string(), "value1".to_string());
                map.insert("key2".to_string(), "value2".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        let all = cache.get_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("key1"), Some(&"value1".to_string()));
        assert_eq!(all.get("key2"), Some(&"value2".to_string()));
    }

    #[tokio::test]
    async fn test_cache_age() {
        let mut cache = AsyncCache::<String, String>::new("test");

        // Age should be None before building
        assert!(cache.age().is_none());

        cache
            .build_cache(|| {
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                Ok(map)
            })
            .await
            .unwrap();

        // Age should be Some after building
        let age = cache.age();
        assert!(age.is_some());
        assert!(age.unwrap() < Duration::from_secs(1));

        // Wait a bit and check age increased
        tokio::time::sleep(Duration::from_millis(50)).await;
        let new_age = cache.age().unwrap();
        assert!(new_age >= Duration::from_millis(50));
    }
}
