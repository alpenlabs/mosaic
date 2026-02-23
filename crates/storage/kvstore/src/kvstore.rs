use std::{error::Error, fmt::Debug, ops::Bound, pin::Pin};

/// A key-value pair returned from range scans.
#[derive(Debug, Clone)]
pub struct KvPair {
    /// The key bytes.
    pub key: Vec<u8>,
    /// The value bytes.
    pub value: Vec<u8>,
}

/// An async stream of key-value pairs.
///
/// This is a lazy iterator that loads items on demand. Call `.next()` to
/// get the next item, or use `.collect()` to load all items.
pub struct KvStream<'a, E> {
    inner: KvStreamFuture<'a, E>,
}

/// The boxed future type inside a [`KvStream`].
type KvStreamFuture<'a, E> =
    Pin<Box<dyn Future<Output = Result<Option<(KvPair, KvStream<'a, E>)>, E>> + Send + 'a>>;

impl<'a, E> KvStream<'a, E> {
    /// Create a new stream from a future.
    pub fn new<F>(fut: F) -> Self
    where
        F: Future<Output = Result<Option<(KvPair, KvStream<'a, E>)>, E>> + Send + 'a,
    {
        Self {
            inner: Box::pin(fut),
        }
    }

    /// Create an empty stream (no items).
    pub fn empty() -> Self
    where
        E: 'a,
    {
        Self {
            inner: Box::pin(async { Ok(None) }),
        }
    }

    /// Get the next item in the stream.
    ///
    /// Returns `Ok(Some((pair, next)))` if there's another item,
    /// or `Ok(None)` if the stream is exhausted.
    pub async fn next(self) -> Result<Option<(KvPair, KvStream<'a, E>)>, E> {
        self.inner.await
    }

    /// Collect all items into a vector.
    ///
    /// **Warning**: This loads all items into memory. Use with caution for large ranges.
    pub async fn collect(self) -> Result<Vec<KvPair>, E> {
        let mut results = Vec::new();
        let mut current = self;

        while let Some((pair, next)) = current.next().await? {
            results.push(pair);
            current = next;
        }

        Ok(results)
    }

    /// Collect up to `limit` items into a vector.
    pub async fn take(self, limit: usize) -> Result<Vec<KvPair>, E> {
        let mut results = Vec::with_capacity(limit.min(64));
        let mut current = self;

        for _ in 0..limit {
            match current.next().await? {
                Some((pair, next)) => {
                    results.push(pair);
                    current = next;
                }
                None => break,
            }
        }

        Ok(results)
    }

    /// Apply a function to each item, stopping on first error.
    pub async fn for_each<F>(self, mut f: F) -> Result<(), E>
    where
        F: FnMut(KvPair),
    {
        let mut current = self;

        while let Some((pair, next)) = current.next().await? {
            f(pair);
            current = next;
        }

        Ok(())
    }
}

/// Async key-value store trait.
///
/// This trait abstracts over different KV backends (FoundationDB, RocksDB, memory).
/// All operations are async to support network-based transactional databases.
///
/// ## Error Handling
///
/// The error type `E` is generic and must implement `Debug + Send`. When used with
/// the state machine, KV errors propagate directly to the STF return type.
///
/// ## Implementation Notes
///
/// - Implementations should buffer writes until commit (for transactional backends).
/// - Range scans should be lazy to avoid loading all data into memory.
/// - Keys and values are arbitrary byte sequences.
/// - Implementations are responsible for any key prefixing/namespacing.
#[async_trait::async_trait]
pub trait KvStore: Send {
    /// The error type for this store.
    type Error: Error + Debug + Send + Sync + 'static;

    /// Get a value by key.
    ///
    /// Returns `Ok(Some(value))` if found, `Ok(None)` if not found.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Set a key-value pair.
    ///
    /// Overwrites any existing value for the key.
    async fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Delete a key.
    ///
    /// No-op if the key doesn't exist.
    async fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error>;

    /// Check if a key exists.
    ///
    /// Default implementation uses `get`, but backends may optimize this.
    async fn exists(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.get(key).await?.is_some())
    }

    /// Scan a range of keys.
    ///
    /// Returns all keys in the given range, in lexicographic order.
    /// Results are loaded lazily via the returned [`KvStream`].
    ///
    /// # Arguments
    ///
    /// * `start` - Start bound (inclusive/exclusive/unbounded)
    /// * `end` - End bound (inclusive/exclusive/unbounded)
    /// * `reverse` - If true, scan in reverse lexicographic order
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::ops::Bound;
    ///
    /// // All keys from "a" (inclusive) to "z" (exclusive)
    /// store.range(Bound::Included(b"a"), Bound::Excluded(b"z"), false)
    ///
    /// // All keys starting from "start"
    /// store.range(Bound::Included(b"start"), Bound::Unbounded, false)
    ///
    /// // All keys
    /// store.range(Bound::Unbounded, Bound::Unbounded, false)
    /// ```
    fn range<'a>(
        &'a self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        reverse: bool,
    ) -> KvStream<'a, Self::Error>;

    /// Clear all keys in a range.
    ///
    /// More efficient than deleting keys one by one for backends that support range deletes.
    async fn clear_range(
        &mut self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
    ) -> Result<(), Self::Error>;
}
