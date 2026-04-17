//! S3-backed [`TableReader`] implementation.
//!
//! Reads garbling table components from object storage. Metadata and
//! translation material are fetched eagerly on construction (they're small).
//! Ciphertext data is streamed via a background tokio task that pre-fetches
//! chunks through a bounded channel. If the HTTP connection drops mid-transfer,
//! the background task automatically resumes from the last successfully
//! delivered byte offset.

use std::{future::Future, sync::Arc};

use futures::StreamExt;
use mosaic_common::Byte32;
use mosaic_storage_api::table_store::{TableMetadata, TableReader};
use object_store::{GetOptions, GetRange, ObjectStore};
use tracing::{debug, error, warn};

use crate::{error::S3Error, paths::TableRootPaths};

/// Maximum retries when opening or resuming a ciphertext stream.
const STREAM_MAX_RETRIES: u32 = 3;

/// Reads a garbling table from object storage.
///
/// Metadata and translation material are loaded eagerly during construction.
/// Ciphertext data is streamed on demand via [`read_ciphertext`](Self::read_ciphertext),
/// backed by a background tokio task that pre-fetches chunks from the object
/// store through a bounded channel.
///
/// If the underlying HTTP connection drops, the background task automatically
/// resumes from the last delivered byte offset.
#[derive(Debug)]
pub struct S3TableReader {
    /// Table metadata (loaded eagerly).
    meta: TableMetadata,
    /// Translation material (loaded eagerly).
    translation: Vec<u8>,
    /// Channel for receiving pre-fetched ciphertext chunks from the background task.
    ct_rx: kanal::AsyncReceiver<Result<Vec<u8>, S3Error>>,
    /// Internal buffer holding the current chunk from the channel.
    buffer: Vec<u8>,
    /// Read position within `buffer`.
    buf_pos: usize,
    /// `true` once the background stream has signalled completion (channel closed).
    eof: bool,
}

impl S3TableReader {
    /// Open a table for reading.
    ///
    /// Fetches metadata and translation material immediately. Spawns a
    /// background task to stream ciphertext data on demand.
    pub(crate) async fn new(
        store: Arc<dyn ObjectStore>,
        rt_handle: tokio::runtime::Handle,
        root_paths: TableRootPaths,
    ) -> Result<Self, S3Error> {
        // Fetch committed version via tokio runtime.
        let (ver_tx, ver_rx) = kanal::bounded_async(1);
        {
            let store = Arc::clone(&store);
            let committed_path = root_paths.committed.clone();
            rt_handle.spawn(async move {
                let result = fetch_committed_version(&store, &committed_path).await;
                let _ = ver_tx.send(result).await;
            });
        }
        let version = ver_rx
            .recv()
            .await
            .map_err(|_| S3Error::Channel("committed version fetch task gone".into()))??;
        let paths = root_paths.version_paths(version);

        // Fetch metadata and translation eagerly via the tokio runtime.
        let (meta_tx, meta_rx) = kanal::bounded_async(1);
        let (trans_tx, trans_rx) = kanal::bounded_async(1);

        {
            let store = Arc::clone(&store);
            let meta_path = paths.metadata.clone();
            let trans_path = paths.translation.clone();
            rt_handle.spawn(async move {
                let meta_result = fetch_metadata(&store, &meta_path).await;
                let _ = meta_tx.send(meta_result).await;

                let trans_result = fetch_translation(&store, &trans_path).await;
                let _ = trans_tx.send(trans_result).await;
            });
        }

        let meta = meta_rx
            .recv()
            .await
            .map_err(|_| S3Error::Channel("metadata fetch task gone".into()))??;

        let translation = trans_rx
            .recv()
            .await
            .map_err(|_| S3Error::Channel("translation fetch task gone".into()))??;

        // Spawn background ciphertext streaming task.
        let (ct_tx, ct_rx) = kanal::bounded_async(crate::STREAM_CHANNEL_CAPACITY);
        {
            let store = Arc::clone(&store);
            let ct_path = paths.ciphertexts.clone();
            rt_handle.spawn(async move {
                stream_ciphertexts(store, ct_path, ct_tx).await;
            });
        }

        Ok(Self {
            meta,
            translation,
            ct_rx,
            buffer: Vec::new(),
            buf_pos: 0,
            eof: false,
        })
    }
}

impl TableReader for S3TableReader {
    type Error = S3Error;

    fn metadata(&mut self) -> impl Future<Output = Result<TableMetadata, Self::Error>> + Send {
        let meta = self.meta;
        async move { Ok(meta) }
    }

    fn read_translation(&mut self) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let translation = self.translation.clone();
        async move { Ok(translation) }
    }

    fn read_ciphertext(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send {
        self.read_ciphertext_inner(buf)
    }
}

impl S3TableReader {
    /// Fill `buf` from the internal buffer or, if exhausted, from the next
    /// channel chunk. Returns the number of bytes written into `buf`.
    async fn read_ciphertext_inner(&mut self, buf: &mut [u8]) -> Result<usize, S3Error> {
        // Serve from the internal buffer first.
        let available = self.buffer.len() - self.buf_pos;
        if available > 0 {
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&self.buffer[self.buf_pos..self.buf_pos + n]);
            self.buf_pos += n;
            if self.buf_pos >= self.buffer.len() {
                self.buffer.clear();
                self.buf_pos = 0;
            }
            return Ok(n);
        }

        if self.eof {
            return Ok(0);
        }

        // Fetch the next chunk from the background streaming task.
        match self.ct_rx.recv().await {
            Ok(Ok(chunk)) => {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                // Buffer any overflow for the next read.
                if n < chunk.len() {
                    self.buffer = chunk[n..].to_vec();
                    self.buf_pos = 0;
                }
                Ok(n)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

/// Read the currently committed table version from the live marker.
async fn fetch_committed_version(
    store: &Arc<dyn ObjectStore>,
    path: &object_store::path::Path,
) -> Result<String, S3Error> {
    let result = store.get(path).await.map_err(|e| match e {
        object_store::Error::NotFound { path, .. } => S3Error::NotFound {
            path: path.to_string(),
        },
        other => S3Error::ObjectStore(other),
    })?;

    let bytes = result.bytes().await.map_err(S3Error::ObjectStore)?;
    let version = std::str::from_utf8(bytes.as_ref())
        .map_err(|e| S3Error::InvalidMetadata(format!("commit marker was not valid utf-8: {e}")))?
        .trim()
        .to_owned();

    if version.is_empty() || version.contains('/') {
        return Err(S3Error::InvalidMetadata(format!(
            "commit marker contained invalid version id: {version:?}"
        )));
    }

    Ok(version)
}

/// Fetch and deserialize metadata from object storage.
async fn fetch_metadata(
    store: &Arc<dyn ObjectStore>,
    path: &object_store::path::Path,
) -> Result<TableMetadata, S3Error> {
    let result = store.get(path).await.map_err(|e| match e {
        object_store::Error::NotFound { path, .. } => S3Error::NotFound {
            path: path.to_string(),
        },
        other => S3Error::ObjectStore(other),
    })?;

    let bytes = result.bytes().await.map_err(S3Error::ObjectStore)?;

    if bytes.len() < 64 {
        return Err(S3Error::InvalidMetadata(format!(
            "expected 64 bytes, got {}",
            bytes.len()
        )));
    }

    let mut output_label_ct = [0u8; 32];
    output_label_ct.copy_from_slice(&bytes[..32]);

    let mut aes_key = [0u8; 16];
    aes_key.copy_from_slice(&bytes[32..48]);

    let mut public_s = [0u8; 16];
    public_s.copy_from_slice(&bytes[48..64]);

    Ok(TableMetadata {
        output_label_ct: Byte32::from(output_label_ct),
        aes_key,
        public_s,
    })
}

/// Fetch translation material from object storage.
async fn fetch_translation(
    store: &Arc<dyn ObjectStore>,
    path: &object_store::path::Path,
) -> Result<Vec<u8>, S3Error> {
    let result = store.get(path).await.map_err(|e| match e {
        object_store::Error::NotFound { path, .. } => S3Error::NotFound {
            path: path.to_string(),
        },
        other => S3Error::ObjectStore(other),
    })?;

    let bytes = result.bytes().await.map_err(S3Error::ObjectStore)?;
    Ok(bytes.to_vec())
}

/// Background task that streams ciphertext data from object storage
/// through a bounded channel.
///
/// Uses a streaming GET for throughput. If the connection drops mid-transfer,
/// the stream is automatically resumed from the last successfully delivered
/// byte offset (via `GetRange::Offset`). Gives up after [`STREAM_MAX_RETRIES`]
/// consecutive failures.
async fn stream_ciphertexts(
    store: Arc<dyn ObjectStore>,
    path: object_store::path::Path,
    tx: kanal::AsyncSender<Result<Vec<u8>, S3Error>>,
) {
    let mut bytes_delivered: usize = 0;
    let mut retries: u32 = 0;

    loop {
        // Open a (possibly resumed) streaming GET.
        let opts = if bytes_delivered == 0 {
            GetOptions::default()
        } else {
            GetOptions {
                range: Some(GetRange::Offset(bytes_delivered)),
                ..Default::default()
            }
        };

        debug!(
            path = %path,
            bytes_delivered,
            resumed = bytes_delivered > 0,
            "ciphertext stream: opening GET"
        );

        let get_result = match store.get_opts(&path, opts).await {
            Ok(r) => r,
            Err(e) => {
                retries += 1;
                if retries > STREAM_MAX_RETRIES {
                    error!(
                        path = %path, bytes_delivered, retries,
                        %e, "ciphertext stream: failed to open after retries"
                    );
                    let _ = tx.send(Err(S3Error::ObjectStore(e))).await;
                    return;
                }
                warn!(
                    path = %path, bytes_delivered, retries,
                    %e, "ciphertext stream: open failed, will retry"
                );
                let backoff = std::time::Duration::from_millis(100 * (1 << retries));
                tokio::time::sleep(backoff).await;
                continue;
            }
        };

        let mut stream = get_result.into_stream();
        let mut stream_failed = false;

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    let len = bytes.len();
                    if tx.send(Ok(bytes.to_vec())).await.is_err() {
                        debug!(
                            path = %path, bytes_delivered,
                            "ciphertext stream: consumer dropped, stopping"
                        );
                        return;
                    }
                    bytes_delivered += len;
                    retries = 0; // Successful data resets the retry counter.
                }
                Err(e) => {
                    retries += 1;
                    if retries > STREAM_MAX_RETRIES {
                        error!(
                            path = %path, bytes_delivered, retries,
                            %e, "ciphertext stream: failed after retries"
                        );
                        let _ = tx.send(Err(S3Error::ObjectStore(e))).await;
                        return;
                    }
                    warn!(
                        path = %path, bytes_delivered, retries,
                        %e, "ciphertext stream: connection lost, will resume"
                    );
                    let backoff = std::time::Duration::from_millis(100 * (1 << retries));
                    tokio::time::sleep(backoff).await;
                    stream_failed = true;
                    break; // Break inner loop to re-open from offset.
                }
            }
        }

        if !stream_failed {
            // Stream completed normally (no more chunks).
            debug!(
                path = %path, bytes_delivered,
                "ciphertext stream: completed"
            );
            return;
        }
    }
}
