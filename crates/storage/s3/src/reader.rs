//! S3-backed [`TableReader`] implementation.
//!
//! Reads garbling table components from object storage. Metadata and
//! translation material are fetched eagerly on construction (they're small).
//! Ciphertext data is streamed lazily via a background tokio task that
//! pre-fetches chunks through a bounded channel.

use std::{future::Future, sync::Arc};

use futures::StreamExt;
use mosaic_common::Byte32;
use mosaic_storage_api::table_store::{TableMetadata, TableReader};
use object_store::ObjectStore;

use crate::{error::S3Error, paths::TablePaths};

/// Reads a garbling table from object storage.
///
/// Metadata and translation material are loaded eagerly during construction.
/// Ciphertext data is streamed on demand via [`read_ciphertext`](Self::read_ciphertext),
/// backed by a background tokio task that pre-fetches chunks from the object
/// store through a bounded channel.
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
        paths: TablePaths,
    ) -> Result<Self, S3Error> {
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
async fn stream_ciphertexts(
    store: Arc<dyn ObjectStore>,
    path: object_store::path::Path,
    tx: kanal::AsyncSender<Result<Vec<u8>, S3Error>>,
) {
    let get_result = match store.get(&path).await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(Err(S3Error::ObjectStore(e))).await;
            return;
        }
    };

    let mut stream = get_result.into_stream();

    loop {
        let chunk_result = stream.next().await;
        match chunk_result {
            Some(Ok(bytes)) => {
                if tx.send(Ok(bytes.to_vec())).await.is_err() {
                    return;
                }
            }
            Some(Err(e)) => {
                let _ = tx.send(Err(S3Error::ObjectStore(e))).await;
                return;
            }
            None => break,
        }
    }

    // Stream complete — dropping tx signals EOF to the receiver.
}
