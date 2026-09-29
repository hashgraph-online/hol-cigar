use crate::ContextError;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Exact token accounting for the rendered context text, excluding the provider chat envelope.
/// Implementations must use an immutable identity for their algorithm and vocabulary.
pub trait TokenCounter {
    /// Algorithm/vocabulary identity; changes invalidate snapshot reuse.
    fn identity(&self) -> &str;
    /// Counts text as ordinary data, including strings resembling special model tokens.
    fn count(&self, text: &str) -> Result<usize, ContextError>;
}

/// Bounds for exact-text token memoization. Either zero limit disables caching.
#[derive(Clone, Copy, Debug)]
pub struct TokenCacheLimits {
    /// Maximum distinct cached strings; also bounds map/queue overhead.
    pub max_entries: usize,
    /// Maximum retained UTF-8 payload bytes, excluding bounded entry/allocator overhead.
    pub max_text_bytes: usize,
}

impl Default for TokenCacheLimits {
    fn default() -> Self {
        Self {
            max_entries: 2048,
            max_text_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Content-free counters for an instance-local token cache.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenCacheStats {
    /// Successful exact-text lookups.
    pub hits: u64,
    /// Requests sent to the underlying tokenizer, including bypasses and errors.
    pub misses: u64,
    /// Current number of distinct entries.
    pub entries: usize,
    /// Current retained UTF-8 text bytes, excluding allocator/entry overhead.
    pub text_bytes: usize,
}

#[derive(Default)]
struct Cache {
    values: HashMap<Arc<str>, usize>,
    order: VecDeque<Arc<str>>,
    stats: TokenCacheStats,
    generation: u64,
}

/// Bounded, thread-safe, exact-text memoization for an immutable token counter.
///
/// Counts are never estimated or added across blocks. Equality checks the complete string, not
/// only a digest. FIFO eviction changes performance only. Errors are never cached. The cache
/// retains source text in memory: own one per privacy boundary and clear/drop it when appropriate.
/// Concurrent misses may compute twice; the expensive tokenizer never runs under the cache lock.
pub struct CachedTokenCounter<T> {
    inner: T,
    limits: TokenCacheLimits,
    cache: Mutex<Cache>,
}

impl<T: TokenCounter> CachedTokenCounter<T> {
    /// Wraps an immutable tokenizer with an empty, instance-local cache.
    pub fn new(inner: T, limits: TokenCacheLimits) -> Self {
        Self {
            inner,
            limits,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Returns counters without exposing retained text.
    pub fn cache_stats(&self) -> Result<TokenCacheStats, ContextError> {
        self.cache
            .lock()
            .map(|cache| cache.stats)
            .map_err(|_| ContextError::Tokenizer)
    }

    /// Drops all retained strings and resets counters. Does not promise allocator zeroization.
    pub fn clear_cache(&self) -> Result<(), ContextError> {
        let mut cache = self.cache.lock().map_err(|_| ContextError::Tokenizer)?;
        let generation = cache
            .generation
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        *cache = Cache {
            generation,
            ..Cache::default()
        };
        Ok(())
    }
}

impl<T: TokenCounter> TokenCounter for CachedTokenCounter<T> {
    fn identity(&self) -> &str {
        self.inner.identity()
    }

    fn count(&self, text: &str) -> Result<usize, ContextError> {
        let generation = {
            let mut cache = self.cache.lock().map_err(|_| ContextError::Tokenizer)?;
            if let Some(value) = cache.values.get(text).copied() {
                cache.stats.hits = cache.stats.hits.saturating_add(1);
                return Ok(value);
            }
            cache.stats.misses = cache.stats.misses.saturating_add(1);
            cache.generation
        };
        let count = self.inner.count(text)?;
        if self.limits.max_entries == 0
            || text.len() > self.limits.max_text_bytes
            || self.limits.max_text_bytes == 0
        {
            return Ok(count);
        }
        let mut cache = self.cache.lock().map_err(|_| ContextError::Tokenizer)?;
        // A concurrent clear must not be undone by an in-flight count retaining old source text.
        if cache.generation != generation || cache.values.contains_key(text) {
            return Ok(count);
        }
        while cache.values.len() >= self.limits.max_entries
            || cache.stats.text_bytes > self.limits.max_text_bytes - text.len()
        {
            if let Some(old) = cache.order.pop_front() {
                cache.values.remove(old.as_ref());
                cache.stats.text_bytes -= old.len();
            } else {
                break;
            }
        }
        let key: Arc<str> = Arc::from(text);
        cache.values.insert(Arc::clone(&key), count);
        cache.order.push_back(key);
        cache.stats.text_bytes += text.len();
        cache.stats.entries = cache.values.len();
        Ok(count)
    }
}

/// Exact UTF-8 byte accounting for diagnostics. These units are not model tokens.
#[derive(Clone, Copy, Debug, Default)]
pub struct Utf8ByteCounter;

impl TokenCounter for Utf8ByteCounter {
    fn identity(&self) -> &str {
        "cigar.utf8-bytes.v1"
    }

    fn count(&self, text: &str) -> Result<usize, ContextError> {
        Ok(text.len())
    }
}

/// Offline o200k_base BPE using the vocabulary embedded in pinned tiktoken-rs 0.12.0.
#[cfg(feature = "bpe")]
pub struct O200kTokenizer(CachedTokenCounter<RawO200kTokenizer>);

#[cfg(feature = "bpe")]
struct RawO200kTokenizer(tiktoken_rs::CoreBPE);

#[cfg(feature = "bpe")]
impl O200kTokenizer {
    /// Loads the embedded vocabulary once; reuse this object across requests.
    pub fn new() -> Result<Self, ContextError> {
        Self::with_cache_limits(TokenCacheLimits::default())
    }

    /// Loads the same exact vocabulary with explicit cache bounds (zero disables caching).
    pub fn with_cache_limits(limits: TokenCacheLimits) -> Result<Self, ContextError> {
        tiktoken_rs::o200k_base()
            .map(|bpe| Self(CachedTokenCounter::new(RawO200kTokenizer(bpe), limits)))
            .map_err(|_| ContextError::Tokenizer)
    }

    /// Content-free cache measurements for this tokenizer instance.
    pub fn cache_stats(&self) -> Result<TokenCacheStats, ContextError> {
        self.0.cache_stats()
    }

    /// Drops cached source strings; the reusable vocabulary remains loaded.
    pub fn clear_cache(&self) -> Result<(), ContextError> {
        self.0.clear_cache()
    }
}

#[cfg(feature = "bpe")]
impl TokenCounter for O200kTokenizer {
    fn identity(&self) -> &str {
        self.0.identity()
    }
    fn count(&self, text: &str) -> Result<usize, ContextError> {
        self.0.count(text)
    }
}

#[cfg(feature = "bpe")]
impl TokenCounter for RawO200kTokenizer {
    fn identity(&self) -> &str {
        "o200k_base.tiktoken-rs-0.12.0.ordinary"
    }

    fn count(&self, text: &str) -> Result<usize, ContextError> {
        Ok(self.0.count_ordinary(text))
    }
}
