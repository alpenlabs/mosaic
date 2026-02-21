//! S3-backed garbling table storage using `object_store`.
//!
//! Spawns a background single-threaded tokio runtime for all I/O. Monoio
//! workers communicate with it via bounded async channels ([`kanal`]).
//!
//! # Storage layout
//!
//! ```text
//! {prefix}/{peer_id_hex}/{index}/ciphertexts
//! {prefix}/{peer_id_hex}/{index}/translation
//! {prefix}/{peer_id_hex}/{index}/metadata
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let store = S3TableStore::new(object_store, "garbling-tables");
//! // Pass to MosaicExecutor as the TableStore implementation.
//! ```

mod error;
mod paths;
mod reader;
mod writer;

use std::future::Future;
use std::sync::Arc;

use mosaic_storage_api::table_store::{TableId, TableStore};
use object_store::ObjectStore;

pub use error::S3Error;

/// Minimum part size for S3 multipart uploads (5 MiB).
#[allow(dead_code)]
const MIN_PART_SIZE: usize = 5 * 1024 * 1024;

/// Buffer size for ciphertext parts. Parts are uploaded when the buffer
/// reaches this size. Larger parts = fewer HTTP requests.
const PART_BUFFER_SIZE: usize = 8 * 1024 * 1024;

/// Bounded channel capacity for streaming data between monoio and tokio.
/// Controls backpressure: the producer blocks when this many chunks are
/// buffered and the consumer hasn't caught up.
const STREAM_CHANNEL_CAPACITY: usize = 4;

/// S3-backed (or any `ObjectStore` backend) garbling table storage.
///
/// All I/O runs on a dedicated single-threaded tokio runtime. The monoio
/// workers on the job scheduler threads interact with this store via
/// runtime-agnostic [`kanal`] channels — no tokio dependency leaks into
/// the caller.
pub struct S3TableStore {
    /// Handle to the background tokio runtime (for spawning tasks).
    rt_handle: tokio::runtime::Handle,
    /// The underlying object store (S3, GCS, local filesystem, in-memory, etc.).
    store: Arc<dyn ObjectStore>,
    /// Path prefix for all garbling tables.
    prefix: String,
    /// Background thread handle. Kept alive for the store's lifetime.
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for S3TableStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3TableStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl S3TableStore {
    /// Create a new table store backed by the given `ObjectStore`.
    ///
    /// Spawns a dedicated single-threaded tokio runtime on a background thread
    /// for all storage I/O. The runtime is shut down when this store is dropped.
    ///
    /// `prefix` is prepended to all object paths (e.g. `"garbling-tables"`).
    pub fn new(store: Arc<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();

        let thread = std::thread::Builder::new()
            .name("s3-table-store".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build tokio runtime for S3TableStore");

                handle_tx
                    .send(rt.handle().clone())
                    .expect("failed to send runtime handle");

                // Park the runtime until the handle is dropped (store is dropped).
                rt.block_on(std::future::pending::<()>());
            })
            .expect("failed to spawn S3TableStore background thread");

        let rt_handle = handle_rx
            .recv()
            .expect("failed to receive runtime handle from background thread");

        Self {
            rt_handle,
            store,
            prefix: prefix.into(),
            _thread: Some(thread),
        }
    }

    /// Run an async closure on the background tokio runtime and return the
    /// result to the (potentially monoio) caller via a channel.
    async fn dispatch<F, T>(&self, f: F) -> Result<T, S3Error>
    where
        F: FnOnce(
                Arc<dyn ObjectStore>,
            )
                -> std::pin::Pin<Box<dyn Future<Output = Result<T, S3Error>> + Send>>
            + Send
            + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = kanal::bounded_async(1);
        let store = Arc::clone(&self.store);
        self.rt_handle.spawn(async move {
            let result = f(store).await;
            let _ = tx.send(result).await;
        });
        rx.recv().await.map_err(|_| S3Error::RuntimeShutdown)?
    }
}

impl TableStore for S3TableStore {
    type Error = S3Error;
    type Writer = writer::S3TableWriter;
    type Reader = reader::S3TableReader;

    fn create(
        &self,
        id: &TableId,
    ) -> impl Future<Output = Result<Self::Writer, Self::Error>> + Send {
        let paths = paths::TablePaths::new(&self.prefix, id);
        let store = Arc::clone(&self.store);
        let rt_handle = self.rt_handle.clone();
        async move { writer::S3TableWriter::new(store, rt_handle, paths).await }
    }

    fn open(&self, id: &TableId) -> impl Future<Output = Result<Self::Reader, Self::Error>> + Send {
        let paths = paths::TablePaths::new(&self.prefix, id);
        let store = Arc::clone(&self.store);
        let rt_handle = self.rt_handle.clone();
        async move { reader::S3TableReader::new(store, rt_handle, paths).await }
    }

    fn exists(&self, id: &TableId) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let path = paths::TablePaths::new(&self.prefix, id).metadata;
        self.dispatch(move |store| {
            Box::pin(async move {
                match store.head(&path).await {
                    Ok(_) => Ok(true),
                    Err(object_store::Error::NotFound { .. }) => Ok(false),
                    Err(e) => Err(S3Error::ObjectStore(e)),
                }
            })
        })
    }

    fn delete(&self, id: &TableId) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let paths = paths::TablePaths::new(&self.prefix, id);
        self.dispatch(move |store| {
            Box::pin(async move {
                // Delete all three components. Ignore NotFound errors.
                for path in [&paths.ciphertexts, &paths.translation, &paths.metadata] {
                    match store.delete(path).await {
                        Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                        Err(e) => return Err(S3Error::ObjectStore(e)),
                    }
                }
                Ok(())
            })
        })
    }
}
