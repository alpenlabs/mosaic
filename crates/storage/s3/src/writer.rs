//! S3-backed [`TableWriter`] implementation.
//!
//! Streams ciphertext data to the background tokio runtime which performs
//! multipart uploads via `object_store`. Translation material and metadata
//! are uploaded into immutable versioned object paths, and the table becomes
//! visible only once the live commit marker is published during
//! [`finish`](S3TableWriter::finish).

use std::sync::Arc;

use bytes::Bytes;
use mosaic_storage_api::table_store::{TableMetadata, TableWriter};
use object_store::ObjectStore;
use tracing::error;

use crate::{
    PART_BUFFER_SIZE,
    error::S3Error,
    paths::{TableRootPaths, TableVersionPaths},
};

/// Commands sent from the monoio caller to the background tokio writer task.
enum WriterCmd {
    /// Append ciphertext bytes.
    Write(Vec<u8>),
    /// Finalize: flush remaining ciphertext, upload translation + metadata.
    Finish {
        translation: Vec<u8>,
        metadata_bytes: Vec<u8>,
    },
}

/// Streams garbling table data to object storage via a background tokio task.
///
/// Ciphertext chunks are buffered and uploaded as multipart parts when the
/// buffer exceeds [`PART_BUFFER_SIZE`]. Translation material and metadata are
/// written under an immutable version prefix, then a live commit marker is
/// published on [`finish`](Self::finish).
///
/// Dropping without calling `finish` aborts the multipart upload.
#[derive(Debug)]
pub struct S3TableWriter {
    /// Channel for sending commands to the background task.
    cmd_tx: kanal::AsyncSender<WriterCmd>,
    /// Channel for receiving the final result from the background task.
    result_rx: kanal::AsyncReceiver<Result<(), S3Error>>,
}

impl S3TableWriter {
    /// Create a new writer. Spawns a background task on the provided tokio
    /// runtime that manages the multipart upload.
    pub(crate) async fn new(
        store: Arc<dyn ObjectStore>,
        rt_handle: tokio::runtime::Handle,
        root_paths: TableRootPaths,
    ) -> Result<Self, S3Error> {
        let version_paths = root_paths.allocate_version_paths();
        let (cmd_tx, cmd_rx) = kanal::bounded_async(crate::STREAM_CHANNEL_CAPACITY);
        let (result_tx, result_rx) = kanal::bounded_async(1);

        rt_handle.spawn(background_writer(
            store,
            root_paths,
            version_paths,
            cmd_rx,
            result_tx,
        ));

        Ok(Self { cmd_tx, result_rx })
    }
}

impl TableWriter for S3TableWriter {
    type Error = S3Error;

    fn write_ciphertext(
        &mut self,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let chunk = data.to_vec();
        let tx = self.cmd_tx.clone();
        async move {
            tx.send(WriterCmd::Write(chunk))
                .await
                .map_err(|_| S3Error::Channel("writer background task gone".into()))
        }
    }

    fn finish(
        &mut self,
        translation: &[u8],
        metadata: TableMetadata,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let translation = translation.to_vec();
        let metadata_bytes = serialize_metadata(&metadata);
        let cmd_tx = self.cmd_tx.clone();
        let result_rx = self.result_rx.clone();
        async move {
            cmd_tx
                .send(WriterCmd::Finish {
                    translation,
                    metadata_bytes,
                })
                .await
                .map_err(|_| S3Error::Channel("writer background task gone".into()))?;

            // Drop the command sender so the background task knows no more
            // commands are coming after Finish.
            drop(cmd_tx);

            // Wait for the background task to complete all uploads.
            result_rx
                .recv()
                .await
                .map_err(|_| S3Error::Channel("writer result channel closed".into()))?
        }
    }
}

/// Background task that runs on the tokio runtime. Receives ciphertext chunks,
/// buffers them into parts, and uploads via `object_store` multipart API.
async fn background_writer(
    store: Arc<dyn ObjectStore>,
    root_paths: TableRootPaths,
    version_paths: TableVersionPaths,
    cmd_rx: kanal::AsyncReceiver<WriterCmd>,
    result_tx: kanal::AsyncSender<Result<(), S3Error>>,
) {
    let result = background_writer_inner(&store, &root_paths, &version_paths, &cmd_rx).await;
    if let Err(e) = &result {
        error!(
            path = %version_paths.ciphertexts,
            %e,
            "background writer failed"
        );
    }
    if result_tx.send(result).await.is_err() {
        tracing::warn!("background writer: result channel closed, caller gone");
    }
}

async fn background_writer_inner(
    store: &Arc<dyn ObjectStore>,
    root_paths: &TableRootPaths,
    version_paths: &TableVersionPaths,
    cmd_rx: &kanal::AsyncReceiver<WriterCmd>,
) -> Result<(), S3Error> {
    // Start a multipart upload for the ciphertext object.
    let mut upload = store.put_multipart(&version_paths.ciphertexts).await?;
    let mut buffer = Vec::with_capacity(PART_BUFFER_SIZE);

    loop {
        let cmd = match cmd_rx.recv().await {
            Ok(cmd) => cmd,
            Err(_) => {
                // Channel closed without Finish — abort the upload.
                upload.abort().await?;
                return Err(S3Error::StreamIo(
                    "writer dropped without calling finish".into(),
                ));
            }
        };

        match cmd {
            WriterCmd::Write(data) => {
                buffer.extend_from_slice(&data);

                // Upload complete parts when the buffer is large enough.
                while buffer.len() >= PART_BUFFER_SIZE {
                    let part: Vec<u8> = buffer.drain(..PART_BUFFER_SIZE).collect();
                    upload.put_part(Bytes::from(part).into()).await?;
                }
            }

            WriterCmd::Finish {
                translation,
                metadata_bytes,
            } => {
                // Upload any remaining buffered ciphertext as the final part.
                if !buffer.is_empty() {
                    let final_part = std::mem::take(&mut buffer);
                    upload.put_part(Bytes::from(final_part).into()).await?;
                }

                // Complete the multipart upload.
                upload.complete().await?;

                // Upload translation material as a single object under the staged version.
                store
                    .put(&version_paths.translation, Bytes::from(translation).into())
                    .await?;

                // Upload metadata as a single object under the staged version.
                store
                    .put(&version_paths.metadata, Bytes::from(metadata_bytes).into())
                    .await?;

                // Publish the immutable version by atomically replacing the live marker.
                // Readers trust only this marker when resolving the visible table version.
                store
                    .put(
                        &root_paths.committed,
                        Bytes::from(version_paths.version.clone()).into(),
                    )
                    .await?;

                return Ok(());
            }
        }
    }
}

/// Serialize [`TableMetadata`] to a fixed 64-byte format.
///
/// Layout: `output_label_ct (32B) || aes_key (16B) || public_s (16B)`
fn serialize_metadata(meta: &TableMetadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(meta.output_label_ct.as_ref());
    buf.extend_from_slice(&meta.aes_key);
    buf.extend_from_slice(&meta.public_s);
    buf
}

use std::future::Future;
