//! S3-backed garbling table storage using `object_store`.
//!
//! Spawns a background single-threaded tokio runtime for all I/O. Monoio
//! workers communicate with it via bounded async channels ([`kanal`]).
//!
//! # Storage layout
//!
//! ```text
//! {prefix}/{peer_id_hex}/{index}/committed
//! {prefix}/{peer_id_hex}/{index}/versions/{version}/ciphertexts
//! {prefix}/{peer_id_hex}/{index}/versions/{version}/translation
//! {prefix}/{peer_id_hex}/{index}/versions/{version}/metadata
//! ```
//!
//! Readers trust only the `committed` marker. A partially-written version is
//! never visible unless that marker is successfully updated.
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

use std::{future::Future, sync::Arc};

pub use error::S3Error;
use futures::StreamExt;
use mosaic_storage_api::table_store::{TableId, TableStore};
use object_store::ObjectStore;

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
        let root_paths = paths::TableRootPaths::new(&self.prefix, id);
        let store = Arc::clone(&self.store);
        let rt_handle = self.rt_handle.clone();
        async move { writer::S3TableWriter::new(store, rt_handle, root_paths).await }
    }

    fn open(&self, id: &TableId) -> impl Future<Output = Result<Self::Reader, Self::Error>> + Send {
        let root_paths = paths::TableRootPaths::new(&self.prefix, id);
        let store = Arc::clone(&self.store);
        let rt_handle = self.rt_handle.clone();
        async move { reader::S3TableReader::new(store, rt_handle, root_paths).await }
    }

    fn exists(&self, id: &TableId) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let path = paths::TableRootPaths::new(&self.prefix, id).committed;
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
        let root_paths = paths::TableRootPaths::new(&self.prefix, id);
        self.dispatch(move |store| {
            Box::pin(async move {
                let mut objects = store.list(Some(&root_paths.prefix));
                while let Some(entry) = objects.next().await {
                    let path = entry.map_err(S3Error::ObjectStore)?.location;
                    match store.delete(&path).await {
                        Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                        Err(e) => return Err(S3Error::ObjectStore(e)),
                    }
                }
                Ok(())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mosaic_common::Byte32;
    use mosaic_net_svc_api::PeerId;
    use mosaic_storage_api::table_store::{TableMetadata, TableReader, TableStore, TableWriter};
    use mosaic_vs3::Index;
    use object_store::memory::InMemory;

    use super::*;

    fn table_id() -> TableId {
        TableId {
            peer_id: PeerId::from_bytes([0x11; 32]),
            index: Index::new(4).unwrap(),
        }
    }

    fn metadata(tag: u8) -> TableMetadata {
        TableMetadata {
            output_label_ct: Byte32::from([tag; 32]),
            aes_key: [tag; 16],
            public_s: [tag.wrapping_add(1); 16],
        }
    }

    async fn read_all_ciphertexts<R: TableReader>(reader: &mut R) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = reader.read_ciphertext(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[tokio::test]
    async fn dropped_writer_is_not_visible() {
        let store = S3TableStore::new(Arc::new(InMemory::new()), "tables");
        let id = table_id();

        let mut writer = store.create(&id).await.unwrap();
        writer.write_ciphertext(b"partial").await.unwrap();
        drop(writer);

        assert!(!store.exists(&id).await.unwrap());
        assert!(matches!(
            store.open(&id).await,
            Err(S3Error::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn committed_marker_controls_visible_version() {
        let store = S3TableStore::new(Arc::new(InMemory::new()), "tables");
        let id = table_id();

        let mut first = store.create(&id).await.unwrap();
        first.write_ciphertext(b"abc").await.unwrap();
        first.finish(b"translation-a", metadata(1)).await.unwrap();

        let mut second = store.create(&id).await.unwrap();
        second.write_ciphertext(b"xyz").await.unwrap();
        second.finish(b"translation-b", metadata(2)).await.unwrap();

        assert!(store.exists(&id).await.unwrap());

        let mut reader = store.open(&id).await.unwrap();
        assert_eq!(reader.metadata().await.unwrap(), metadata(2));
        assert_eq!(reader.read_translation().await.unwrap(), b"translation-b");
        assert_eq!(read_all_ciphertexts(&mut reader).await, b"xyz");

        store.delete(&id).await.unwrap();
        assert!(!store.exists(&id).await.unwrap());
    }
}
